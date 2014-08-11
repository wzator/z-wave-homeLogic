<?php
/*  weathergraphs.php v 2.0 for ws3600
 *  Copyright 2004, Kenneth Lavrsen
 *  Copyright 2005, Grzegorz Wisniewski, Sander Eerkes
 *  This program is published under the GNU Public license
 */
include 'graph.php';

$fil=fopen("./log3600.log","r");
$i=0;
fseek ($fil, -130000, SEEK_END);
$streng = fgets($fil, 1000);
while (!feof($fil)) {
    $streng = fgets($fil, 1000);
    $components = preg_split("/[\s]/", $streng);
    if (IsSet($components[14]))
    {
        $time[$i]= $components[2];
        $date[$i]= $components[1];
        $value1[$i]= $components[14];
        $i++;
    }    
}
fclose($fil);

$numberof = count($time);
$start = $numberof - (24*6*8);



//Pressure First
$line = new graph(640,400);
$line->parameter['label_font'] = 'arial.ttf';
$line->parameter['title'] = 'Rain total';
$line->parameter['x_label'] = 'Day';
$line->parameter['x_axis_text'] = 24*6;
$line->parameter['x_grid'] = 'none';
$line->parameter['x_axis_angle'] = 60;
$line->parameter['tick_length'] = 0;
$line->parameter['y_label_left'] = 'mm';
$line->parameter['y_min_left'] = 0;
$line->parameter['y_max_left'] = 1000;
$line->parameter['y_decimal']= 0;
//$line->parameter['num_x_ticks'] = 7;
$line->parameter['y_axis_gridlines'] = 11;
$line->parameter['point_size'] = 6;
$line->parameter['shadow'] = 'none';

$i=$start;
while (substr($time[$i],0,5) != "00:00")
{
    $i++;
}
$start=$i-1;

for ($i=$start,$j=0 ; $i < $numberof ; $i++,$j++)
{

    $line->x_data[$j]= substr($date[$i],5,6);

/*    if (substr($time[$i],0,5) == "00:00")
    {
        $line->x_data[$j]= substr($date[$i],0,6);
    }
    else
    {
        $line->x_data[$j]= "";
    }
*/
//    $line->x_data[$j]= $time[$i];
    $line->y_data['Raintotal'][$j]= $value1[$i];
}

// format for each data set
$line->y_format['Raintotal'] = 
  array('colour' => 'red', 'line' => 'line', 'point' => 'dot');

// order in which to draw data sets.
$line->y_order = array('Raintotal');

// draw it.
$line->draw();


?>
